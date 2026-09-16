rule sig_20160824_37ed2dcf60734ad53463f53686590de1 {
  meta:
    description = "datamaliciousorder - file 20160824_37ed2dcf60734ad53463f53686590de1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cd304a4edbd72c8cc88e2a5af832221024d28c871c2441690fe70656e5347cb"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}