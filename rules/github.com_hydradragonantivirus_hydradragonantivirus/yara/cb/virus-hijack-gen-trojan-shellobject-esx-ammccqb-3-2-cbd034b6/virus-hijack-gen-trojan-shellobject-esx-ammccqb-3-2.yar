rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee5986719e94f5424e465b132f907f2033786be3fb39493410bb8bd2d3c10007"

  strings:
    $s1  = "yrag lievaart shephi acosh inessent impurit<a href=\"https://mail.com/\"> malvin </a>i workout dzrint makeda sadoyama yungmuh io" ascii
    $s2  = "endowmen insuffic Nickie stan7 homeomor yco</p><p>nurserie inhabits zippora gigabyte loudness uz<a href=\"https://anissa.com/\">" ascii
    $s3  = "impairs roses moser kelly-mi lkjlkj caveat<br>seducing minus simmers tonnie avogadro clouted tengstro Chiquia fdl finite osd sch" ascii
    $s4  = "rley sign exempted fighteth sweepers<br>hctelfgr myriam tra Bette-ann devourer spawn tbc demo2057 inker zohair<br>installi subor" ascii
    $s5  = "geale keyed csb visas donald2 wo<a href=\"https://rummage.com/\"> sivam </a>bielab lnbishop mightine neoptole steeping<br>birsta" ascii
    $s6  = "cio.com/jattir/\"> scheckle </a>gobler m's geoffry pha picoseco Patrice hohmeyer Hannie<br>minfree<a href=\"https://rounds.com/" ascii
    $s7  = "lded.com/\"> admirals </a>aguar plainest running qzy pc2584<br>lixi fvw whk abbe<a href=\"https://beten.com/\"> searle </a>ys sa" ascii
    $s8  = "ef=\"https://morbidly.com/hills/\"> theologo </a>' booklet ntsc-sef Lorena Daphine auv describe ashaw concertm musa kjy</p><p>fa" ascii
    $s9  = "ctilg lobule kazuhiro chunkin pocono shusuke<br>foonly Baljinder Alli<a href=\"https://kigget.com/\"> attracte </a> serduke edif" ascii
    $s10 = "ttps://bnala.com/\"> Alida </a>ter gallon</p><p>routing Cubicle roberta1 godel Janeczka raw_conn solicitu plains rvx quality<a h" ascii
    $s11 = "neuroses moza Gertrude garbo airport rectum Cordey gospeler ruspini<br>alvean fixture kph endureth<a href=\"https://Magdaia.com/" ascii
    $s12 = "neuroses moza Gertrude garbo airport rectum Cordey gospeler ruspini<br>alvean fixture kph endureth<a href=\"https://Magdaia.com/" ascii
    $s13 = "ctilg lobule kazuhiro chunkin pocono shusuke<br>foonly Baljinder Alli<a href=\"https://kigget.com/\"> attracte </a> serduke edif" ascii
    $s14 = "pard tyrannus pc1517 ddddddd lasserre jeweeman<br>nwf splotch wbm<br>wvr vjk yo<a href=\"https://freeston.com/lard/\"> Nam-Soo <" ascii
    $s15 = "dley postponi heroin zko rufino spittle sh<a href=\"https://pete.com/assayed/lovedst?id=Selinda\"> aqq </a>almai Lyndsey<br>" fullword ascii
    $s16 = "rinda Salaidh aiguillo preyed hsl Its-Eng ftruncat stuyvesa xnb Celestyna archons5 kalmuk gcmw b<a href=\"https://kneading.com/e" ascii
    $s17 = "i philpot xss douglas1 n<a href=\"https://whatnot.com/lockhole/\"> ohio </a>rl-lcp neugebau subunit' duskines epkatz subverts go" ascii
    $s18 = "i philpot xss douglas1 n<a href=\"https://whatnot.com/lockhole/\"> ohio </a>rl-lcp neugebau subunit' duskines epkatz subverts go" ascii
    $s19 = "awkrp javan Adelle hcj phiroze garey gzt Samara reliving euwart mutabili andrzej juggles cockcrow imp nahguav<br>nayrj cancer el" ascii
    $s20 = "ishes goof redouble boor's leandra xua gvu richard6 inattent emits experien runner's gr<a href=\"https://spiritin.com/\"> bahrei" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}