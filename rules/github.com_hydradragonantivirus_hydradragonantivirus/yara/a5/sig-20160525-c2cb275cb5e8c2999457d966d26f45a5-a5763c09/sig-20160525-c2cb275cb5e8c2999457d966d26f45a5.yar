rule sig_20160525_c2cb275cb5e8c2999457d966d26f45a5 {
  meta:
    description = "datamaliciousorder - file 20160525_c2cb275cb5e8c2999457d966d26f45a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "161996a409a31b417bac2012b3c1c99bb0a9873e917e77a24df705513c7a5688"

  strings:
    $s1 = "rapt rav\\n;\"e6x\\\\epf6x\\\\\" = dnenoisilloct rav\\n;\"96x\\\\rw\" = gedotdart rav\\n;\"56x\\\\t\" = keppelt rav\\n;\"xe45x" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}