rule Virus_Hijack_Trojan_Agent_DQQO_150_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_150_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8c4c1490ac1f408fd9ea03482779c1d0f8322def790f7acbbef0ec635184613"

  strings:
    $s1  = "#@%SystemRoot%\\inf\\unregmp2.exe,-155A..\\..\\..\\..\\..\\..\\Program Files\\Windows Media Player\\wmplayer.exe" fullword wide
    $s2  = "C:\\Program Files\\Windows Media Player\\wmplayer.exe" fullword ascii
    $s3  = " * Components.utils.import(\"resource://gre/modules/JSON.jsm\");" fullword ascii
    $s4  = " * Utilities for JavaScript code to handle JSON content." fullword ascii
    $s5  = "   * content which might be executed during its evaluation" fullword ascii
    $s6  = " * See http://www.json.org/ for comprehensive information about JSON." fullword ascii
    $s7  = "Outlook Express.lnk=@xpsp1res.dll,-11004" fullword ascii
    $s8  = " * The Original Code is Mozilla code." fullword ascii
    $s9  = " * Portions created by the Initial Developer are Copyright (C) 2006-2007" fullword ascii
    $s10 = "// from http://www.json.org/json.js (public domain'd)" fullword ascii
    $s11 = "// * An optional key blacklist has been added to JSON.toString" fullword ascii
    $s12 = " * Import this module through" fullword ascii
    $s13 = "   * Converts a JavaScript object into a JSON string." fullword ascii
    $s14 = "   * Converts a JSON string into a JavaScript object." fullword ascii
    $s15 = "          // have to manually pre-process the object)" fullword ascii
    $s16 = "   * @return a JavaScript object for the given JSON representation" fullword ascii
    $s17 = "  toString: function JSON_toString(aJSObject, aKeysToDrop) {" fullword ascii
    $s18 = "visua/* ***** BEGIN LICENSE BLOCK *****" fullword ascii
    $s19 = " * Note: For your own safety, Objects/Arrays returned by" fullword ascii
    $s20 = "   * @param aKeysToDrop is an optional array of keys which will be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}