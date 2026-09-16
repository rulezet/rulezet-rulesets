rule sig_20160525_9bc944782764fbaa5644f8905e536072 {
  meta:
    description = "datamaliciousorder - file 20160525_9bc944782764fbaa5644f8905e536072.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f5781462d3ec0df02661d3f775e3e201496d2d93dc06b3da3c2f081aefb8a78"

  strings:
    $s1 = "rape nruter{)(me noitcnuf( ,gsme + eixode+imd+rerednerd+cthd + tsilslianbmuhtod+ssorcad + sdnetd+))(};modnard nruter{)(deerdd no" ascii
    $s2 = "47x\\\\ce\" = tsilslianbmuhtog rav;};modnarh nruter{)modnarh(ecapsetihwxelfh noitcnuf;};mh nruter{)mh(dnenoisilloch noitcnuf;};s" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}