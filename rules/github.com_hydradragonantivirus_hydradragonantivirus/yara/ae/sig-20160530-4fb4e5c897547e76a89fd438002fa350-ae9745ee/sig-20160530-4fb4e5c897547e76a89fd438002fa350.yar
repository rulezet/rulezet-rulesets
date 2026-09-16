rule sig_20160530_4fb4e5c897547e76a89fd438002fa350 {
  meta:
    description = "datamaliciousorder - file 20160530_4fb4e5c897547e76a89fd438002fa350.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "165eb0057aab7cfba696b846869c1e8db240ccfeeb97e477a93bb687cadf994b"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aqmh02obgo7.length;i++)if(i%2==0)x.push(aqmh02obgo7[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}