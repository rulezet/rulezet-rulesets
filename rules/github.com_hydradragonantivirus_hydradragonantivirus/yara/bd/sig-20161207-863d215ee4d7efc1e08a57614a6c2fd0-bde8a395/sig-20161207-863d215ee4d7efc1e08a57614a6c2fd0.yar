rule sig_20161207_863d215ee4d7efc1e08a57614a6c2fd0 {
  meta:
    description = "datamaliciousorder - file 20161207_863d215ee4d7efc1e08a57614a6c2fd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a132e257ae5dc0e0c3057946d0e3a8f62a9912263093497e4345582d4022d34"

  strings:
    $s1 = " new Date();vIy9[\"setUTCFullYear\"](\"2003\");if (vIy9.getUTCFullYear().toString(10) == \"2003\") {var vGEj4 = vKn5.split(\"###" ascii
    $s2 = "var vYVf7 = new Function(\"vKn5\", '{return vKn5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWVc6 = new Function(\"vKn5" ascii
    $s3 = "turn vGEj4.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vYVf7 = new Function(\"vKn5\", '{return vKn5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vWVc6 = new Function(\"vKn5" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}