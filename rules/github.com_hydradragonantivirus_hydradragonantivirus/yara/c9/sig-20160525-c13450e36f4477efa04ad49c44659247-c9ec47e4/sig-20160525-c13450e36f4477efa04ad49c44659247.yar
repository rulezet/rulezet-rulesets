rule sig_20160525_c13450e36f4477efa04ad49c44659247 {
  meta:
    description = "datamaliciousorder - file 20160525_c13450e36f4477efa04ad49c44659247.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2636361ded42636970bd1c28468b333dc0dfd9095a0f790bec4b18863b370c17"

  strings:
    $s1 = "rav\\n;\"e37x\\\\\" = dnenoisillock rav\\n;\"46x\\\\n\" = mk rav\\n;\"l35x\\\\\" = keppelk rav\\n;\"56x\\\\56x\\\\\" = ecapsetih" ascii
    $s2 = " = suidarelcitrapd rav\\n;\"e6x\\\\ott\" = gedotdard rav\\n;\".37x\\\\\" = keppeld rav\\n;\"36x\\\\\" = ecapsetihwxelfd rav\\n;" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}