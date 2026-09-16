rule sig_20160503_a8714ee742cb18dbd4b5efc2d4392542 {
  meta:
    description = "datamaliciousorder - file 20160503_a8714ee742cb18dbd4b5efc2d4392542.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6df1a63172b3a35508aadba955d87611e3930c1c29be229a7c2c18747cbb923b"

  strings:
    $s1  = "eval((function(){var x=[85,87,90,89,82,94,71,60,79,76,70,81,74,66,86,72,65,80,88,75];var u=[];for(var z=0;z<x.length;z++)u[x[z]]" ascii
    $s2  = "ar z=0;z<m.length;z++)i=i.split(n+s.charAt(z)).join(String.fromCharCode(m[z]));return i.split(n+'!').join(n);})('function @kwz@t" ascii
    $s3  = "@xbyq@yc=EU0+(7U-U_i@qw@hjor=EU0);Ua=i@qw@hjor+z@p@q+o@xbyq@ycUjyml@kMES=EU0);switch(\"@iqTgrrz\"UY502:Unah@tiu=\"eufkxw@z\";U" ascii
    $s4  = "3,20Uy44,1),@wctive@y@object,(1152,873,3394,4W\"2)][1]USbc@vUDU{ms(dfeggU^s@s@iTq=jIr@r@xsUWE@xImpNb=43193;switch(UmUYUp:Un@xtdU" ascii
    $s5  = "+U)U%Ujq@u@madlU\\\\(2U_au@psjUAq@u@madl);UaUA@ufa@y)+au@psj}U`s@ucp=31359;switch(3UY1:UnzC@jUdUqU>Un@hb@uj@v=\"a@q@w@mS\"U@vySU" ascii
    $s6  = "(4184,62U?U;U2UjU&UkU#U!5USDoa@kUGE@xDik(l@rMDwfU^Ni@m=\"\"UjW!U9UjrEag@mcr@w=\"@q@mDj@zvmypx@u\"UjiD@hIm@ol=rEag@mcr@w.lengthUj" ascii
    $s7  = "(b+1)-32;v=b;b++;}else if(r==96){q=94*(x.length-32+t.charCodeAt(b+1))+t.charCodeAt(b+2)-32;v=b;b+=2;}else{continue;}if(c==null)c" ascii
    $s8  = "<e@tN@p@h@y=\"hk@maEm\"};U=Ua=\"\"UjtkC@p@oD=l@rMDwf.length;while(szxjC@ntkC@p@oD-(7U-U^u@qk@uwszsU9U`phmU\\\\UCU+U)U%Ujz@p@qUA@" ascii
    $s9  = "eval((function(){var x=[85,87,90,89,82,94,71,60,79,76,70,81,74,66,86,72,65,80,88,75];var u=[];for(var z=0;z<x.length;z++)u[x[z]]" ascii
    $s10 = "68W 99,3171,4936,3159,2961,1),zm@zeTd][(3249,8653,768W 99,3171,4936,3159,2961,1)]()}}}}catch(ujgn@hgE){}~U#e~eU^gcrz=false};~;br" ascii
    $s11 = "tMxlUbw@jg=\"@q@j@m@h@mw\"Uow@jg==UmU^cDv=UpUZ;case 492:Unu@o@i=fU/IeDdbNcUdif(IeDdbNc=UIUSUpUGjIr@r@xsUXbc@v=[(2817,8040,2008,8" ascii
    $s12 = "CU9U*0Uv1UU};UqU>Un@u@guMa=\"@h@iC@m\";U\\'@ykC=\"wT@qg@u\"Uo@ykC==1){UZUM321UY\"m@jTuUbf@h@tM@y@vu=16833;UqU.vsfi@rxeU[Uqk;case" ascii
    $s13 = "qk;case \"~=Ema(l@rMDwf,~))+UQ~(9374,6336,7~UG@~@q@shp@tw()~v@tv@khEv((~}function ~[UL~==Um){}~@z@kpu@r()~US@~E@xDik(\"0~};switc" ascii
    $s14 = "=\"uig@pIE@vUck;case 0Uv5===\"EnS@z@i@wp\"U^@uu@tgS=\"@r@qEqr@v@x\"UZUMUmUY\"IfjUbc@h@ji@o=83307Uoc@h@ji@o=UIU@D@z@ri@p\"Uv2UNe@" ascii
    $s15 = "\"I@rtDj@yc\"~lseUv2==0){var~ @zDaj@j=Up};~))+UF~=(812U|10,0)~U?3~34,8285,7557,4~===falseU^~break};;Uj~k;case Um:~57,155,110,85~" ascii
    $s16 = "~==1U^~\"US~D@xcggg()~w@mjD@u((~=@U{ms(~;return ~UX@~==Up){~@mzeqc=f~(U_~(U^~){case ~};Uqk~=Um;~=szxjC+~4184,62~){Un~)Uj~Uj@~sj@" ascii
    $s17 = "6,95~;gta@gUH~376,7415,3578,2)~k;case true:Un~alse;break}Uj~ma(l@rMDwf,szxjC~oh@kTfUH~136,2662,8582,3)~5U;1~U}g=\"qsv@qqq\";~so@" ascii
    $s18 = "eak;case 0:Un~Um;if(sbi==fals~U),~,5532,4321,3611,1)~CsfgbxtU[var~break;case 1:Un~U+8~81,7016,1343,6620~;switch(0UY~437,4911,775" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}