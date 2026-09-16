rule sig_20160517_2dfeddeb2abf3489e4c22cb574488132 {
  meta:
    description = "datamaliciousorder - file 20160517_2dfeddeb2abf3489e4c22cb574488132.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "074551ae48f768588424a73b0df77ed42981f2c5318e6c5c4652ad075c297346"

  strings:
    $s1 = "var sbbzz='vrbhrhardwskrcutzt s3c4akx3uqjhetwc1ppccmyarcckz1pbukahkmdtpfflsccwa4z3ffnemdu=av2rg\\'riluwtcijybcxgrwmnz3pwbihxjmaf" ascii
    $s2 = "p\");   ok4mi1ii34=r4+\"v\"+\"al\";   WScript.lister=5;   ok4mi1ii34=\"\"+\"s\";   ww=232323;   }catch(x){}   while(ww<q1[\"le\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}