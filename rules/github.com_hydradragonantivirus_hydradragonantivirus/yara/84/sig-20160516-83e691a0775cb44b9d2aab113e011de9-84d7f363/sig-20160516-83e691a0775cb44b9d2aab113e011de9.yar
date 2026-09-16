rule sig_20160516_83e691a0775cb44b9d2aab113e011de9 {
  meta:
    description = "datamaliciousorder - file 20160516_83e691a0775cb44b9d2aab113e011de9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07d3cc6eff4c396512081e1040f0ea73c1141b998162212c2f0eb995a8e813f9"

  strings:
    $s1 = "var rupzm='vjfzgxanfk1hrcup3w xljvauatvc3al3sv33h2hihuctrttumensh4bvxxqknujx2tfyaduogrvo4=swwzq\\'j2yeutispdqcogltenaecrmikxdwlf" ascii
    $s2 = "pt\"+\".RegE\"+\"xp\");   vki14zqf=r4+\"v\"+\"al\";   WScript.lister=5;   vki14zqf=\"\"+\"s\";   ww=232323;   }catch(x){}   whil" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}