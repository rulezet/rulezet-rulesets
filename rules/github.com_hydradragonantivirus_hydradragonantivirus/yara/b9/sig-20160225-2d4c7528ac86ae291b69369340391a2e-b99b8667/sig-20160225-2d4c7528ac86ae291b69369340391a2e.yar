rule sig_20160225_2d4c7528ac86ae291b69369340391a2e {
  meta:
    description = "datamaliciousorder - file 20160225_2d4c7528ac86ae291b69369340391a2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ab20a0e078e53cf012496d1ae8d6ffd29b8648a78011ce56339766d27e9a2f2"

  strings:
    $s1 = "    while (statisticsReaction[\"r\\u0065a\" + \"\\u0064\" + \"ys\\u0074a\\u0074e\"] < ((Math.pow(187, 2)-34725),(100,4))) {" fullword ascii
    $s2 = "function String.prototype.abortTaboo(a) {return this;} " fullword ascii
    $s3 = "    expertFlag = this[\"\\u0057\\u0053\" + \"\\u0063\\u0072i\\u0070\" + \"\\u0074\"][\"\\u0043r\\u0065\\u0061\" + \"\\u0074e\\u0" ascii
    $s4 = "        this[\"WS\\u0063r\" + \"\\u0069\\u0070t\"][\"S\\u006ce\\u0065p\"](((49*4+7)-(1^102)));" fullword ascii
    $s5 = "    statisticsReaction = this[\"\\u0057S\\u0063\" + \"\\u0072\\u0069p\\u0074\"][\"\\u0043\\u0072\\u0065\\u0061\" + \"\\u0074eO\"" ascii
    $s6 = "    deformationSolid = this[\"WS\\u0063r\" + \"\\u0069\" + \"\\u0070t\"][\"\\u0043\\u0072\\u0065\" + \"at\" + \"\\u0065\\u004f" ascii
    $s7 = "    expertFlag = this[\"\\u0057\\u0053\" + \"\\u0063\\u0072i\\u0070\" + \"\\u0074\"][\"\\u0043r\\u0065\\u0061\" + \"\\u0074e\\u0" ascii
    $s8 = "    deformationSolid = this[\"WS\\u0063r\" + \"\\u0069\" + \"\\u0070t\"][\"\\u0043\\u0072\\u0065\" + \"at\" + \"\\u0065\\u004f" ascii
    $s9 = "    statisticsReaction = this[\"\\u0057S\\u0063\" + \"\\u0072\\u0069p\\u0074\"][\"\\u0043\\u0072\\u0065\\u0061\" + \"\\u0074eO\"" ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}