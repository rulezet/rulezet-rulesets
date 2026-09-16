rule sig_20170130_f04214d83ada1d982d669a1e593412af {
  meta:
    description = "datamaliciousorder - file 20170130_f04214d83ada1d982d669a1e593412af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33b1593f1dc3c65990fb80edfd8d03f5c1b6b982e4bbf11797f02d49c3dcb6c1"

  strings:
    $s1  = "uqzoresopopvappukvykjidkiwyfzofdishyvnexcolxecofliqliqonjawydofgufzunizupexvokvurqygwaroqmyvequwqodhazzowlumhixatgihaxxiqnumtuko" ascii
    $s2  = "e998imme\", \"kzesvy704irsu\", \"gny706aq\", true, \"adto988erxi\", \"zy894gtarfe\", true, [\"Get\", \"zuh247jy\"]][10][0] + [tr" ascii
    $s3  = "wa440ovo\", true][8][0] + [true, true, true, true, \"yqlog411ijn\", [true, \"ifk328psa\", \"iuj\"], \"gdis897upp\", true, \"yqde" ascii
    $s4  = " \"idt259aso\", true, true, \"yfd132adnu\", \"uhi629oged\", true, \"aqfe789wqevw\", true, \"wfek474sly\", [true, \"Get\", true]]" ascii
    $s5  = "nk581uc\", true], true, \"ytyx264urv\", \"runhe703wtorno\", true, true, true, true][4][0] + [true, [\"ysug657kigho\", \"en\"], " ascii
    $s6  = "if ([true, true, true, \"ije721ab\", \"ivehq719ucroh\", true, true, true, \"emhyxg223ijb\", new Function([true, \"cili872axy\", " ascii
    $s7  = "iqogijyqdonrovkyztuzseglovvadatfosehaduwiwavilfohyjunehmonzukoklugcigbywgyklyrjiwibvigwidlirmojyxevferifizugravipdakimezafjekkyk" ascii
    $s8  = "zymujnudgicnemhebzuxumcudezitcylvadsizizexbedagfarutqymaqucsargagkyluqvupugorojikawuxijjydledqorsilfiplanziwtedagperynmilytogriq" ascii
    $s9  = "8bunve\", true, \"rej364vtuli\", \"ynw494eh\", \"ymfadq438evov\", true, \"ajla732zpisi\"][2][1] + [\"ogozb603yhyt\", \"uqzaxp454" ascii
    $s10 = " \"urvybc401ysy\", \"pagy391eb\", true, \"yjxylf615fsehju\", true][2][0] + [\"yhb592oluw\", true, true, true, true, true, \"am65" ascii
    $s11 = "5eqpipd\", true, \"wvuxi932ijup\"][0][2] + [\"eve615ujarq\", true, true, true, [true, \"OD\"], \"agozb443upmy\", \"khy293wevi\"," ascii
    $s12 = ", \"ydok963enb\", \"wj.\"], true, \"yg192zpex\", \"opha844oxo\", \"fa585zo\", true, \"nximo390irh\"][4][2] + [\"hqo645sny\", tru" ascii
    $s13 = "733myc\", true][8][2] + [true, \"vovje607quz\", true, \"en519uver\", \"aqgiwt635hvub\", [\"ct\", true], \"yjfuhn891bme\", \"ary6" ascii
    $s14 = "tkal\", \"emi946wyn\", \"mxahe188la\", true][4][0] + [true, \"ippi665ymes\", [\"L2\", \"ecu148ma\", \"uv629bac\"], \"bgah266ip\"" ascii
    $s15 = "tsyx\", [\"/mo\", true], \"nesno847akk\", true, true, \"ovp485ymu\", true, true, \"acw992okl\", \"ofip967igki\", true][2][0] + [" ascii
    $s16 = "z303ipip\", \"abypk745uqi\", [true, \"B.\"], true, \"suff294uhgy\"][8][1] + [true, true, [true, \"St\", \"oqj720yc\"], \"qzotbe4" ascii
    $s17 = "lFo\", \"oja639zu\"], \"ovtalg777dety\", true, true, true, true][5][1] + [\"amf981ksunt\", true, true, \"og559ve\", [true, true," ascii
    $s18 = "qe174ajda\", true, [\" ==\", true, true], \"iff872bkuhvo\"][8][0] + [true, [\" 'u\", true], true, true, \"xezri621edneg\", \"de8" ascii
    $s19 = "icna703te\", \"efa171mvi\", \"ynep781ahv\", \"ilpyrr316qka\"][5][1] + [\"po986akm\", \"omfogf242axqan\", true, true, \"qpat991on" ascii
    $s20 = "e, true, \"ic769ytfy\", true, true, \"illi470reto\", \"xe600icyn\", true, \"ozyn208nesa\", true, true, [\"htt\", \"atpa185enac\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}