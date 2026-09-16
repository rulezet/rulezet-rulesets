rule sig_20161208_60237893bf641590a166f45db056d0bd {
  meta:
    description = "datamaliciousorder - file 20161208_60237893bf641590a166f45db056d0bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "611620224cb55f864bbd0664b704f58483874d6202d163258e96028f29e4b55d"

  strings:
    $s1 = "= new Date();vLCt6[\"setUTC\"+\"FullYear\"](\"2003\");if (vLCt6.getUTCFullYear().toString(10) == \"2003\") {var vGYc3 = vQv8.spl" ascii
    $s2 = "var vNPp9 = new Function(\"vQv8\", '{return vQv8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLBu4 = new Function(\"vQv8" ascii
    $s3 = "\"); return vGYc3.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNPp9 = new Function(\"vQv8\", '{return vQv8[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vLBu4 = new Function(\"vQv8" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}