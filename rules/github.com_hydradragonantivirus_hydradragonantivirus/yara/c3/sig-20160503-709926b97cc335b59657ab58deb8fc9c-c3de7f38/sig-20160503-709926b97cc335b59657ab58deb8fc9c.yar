rule sig_20160503_709926b97cc335b59657ab58deb8fc9c {
  meta:
    description = "datamaliciousorder - file 20160503_709926b97cc335b59657ab58deb8fc9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c623fb2a4a34ff5798aae7fb5dddf80e62833dd46787c9f01723e3c9a35f20"

  strings:
    $s1  = "eval((function(){var r=[74,65,76,82,88,89,75,60,85,90,80,81,70,72,71,79,86,66,94,87];var j=[];for(var n=0;n<r.length;n++)j[r[n]]" ascii
    $s2  = "ar n=0;n<g.length;n++)v=v.split(f+p.charAt(n)).join(String.fromCharCode(g[n]));return v.split(f+'!').join(f);})('function @z@moz" ascii
    $s3  = "v=\"yMlw@k\";break}JJjrl(J`y@oeETM@sT=[(4437,2423,4786,5481,7725,7166,3093,6703,1),@hctive@k@vbject,(62,5042,4481,544,1777,340,6" ascii
    $s4  = "()~}function ~Ja;if(~)+I@j@g@q(~=@tEc@o@m(~JT@~532Jd@~(1520,628~=jbJl+~rnbMj@t@l~jbJl);~;return ~;switch(~J^@~(J`@~,9479,1)~;bre" ascii
    $s5  = "9208,49Jo92,4616,3826,2960,9703,8592,6360,0))};bEat@qEb(@jJt,@xTNfIoD)JJM@jsSm(dsC@gJ`cNeJKcNe==\"T@z@sjuw@t@l\"){}JTJj}try{@z@m" ascii
    $s6  = "w@wcc==1J`tefdn@qvJe};break}JU277J]\"bx@x\":if(3===\"pn@g@g@w@h@w@s\"J`v@vzxr=\"v@xv@v@u@hJ<1Jdl@ji@i=26876J;JR=\"\"Jcg@se@z=@ja" ascii
    $s7  = "ngth;while(jbJl@ng@se@z-J>J4J`z@t@xb@jC=J0J#JxJ$JcbjMJQJPJ2JXJctNfS@ozJ-bjM)JclM@m@k@ws@wJ-jbJl+J>J4)Jcz@xnwJ-JSJR=z@xnw+tNfS@oz" ascii
    $s8  = "JJI@g@Jqc@s(J`t@o@snnl=\"@h\"JTt@o@snnlJCoJp(){switch(402J]fJZ @slm@xM=13929Jgslm@xMJ=c@r@kJ \"jm@v\"JdSkJq@j=\"jje@i@qqJkSkJq@j" ascii
    $s9  = "eval((function(){var r=[74,65,76,82,88,89,75,60,85,90,80,81,70,72,71,79,86,66,94,87];var j=[];for(var n=0;n<r.length;n++)j[r[n]]" ascii
    $s10 = "dId=~lseJ`u@rbzj@tc~J/l~@iqr=\"@luqm@x@jj\";~k@w@ov@goE=\"@soCT\"~J]true:var @~=@iz@lqN(@jauD@g,~J1)~0976Jggsov==fa~(3874,4252,1" ascii
    $s11 = "(y+1)-32;o=y;y++;}else if(t==96){z=94*(r.length-32+d.charCodeAt(y+1))+d.charCodeAt(y+2)-32;o=y;y+=2;}else{continue;}if(m==null)m" ascii
    $s12 = "}}catch(hf@gzI){}~=false}JA~=true}JA\"~reak;case trueJd~6610,6553,3681,4735~5,5720,7404,5544,0)~J*i~if(S@iqr=Je){var~k@q@pk\"Jdj" ascii
    $s13 = "ak};~alse:var~+tDrm@v(~){}Jc~){case ~()Jc~ k@qD@q~){var ~=Jj~gsov=1~;var ~:var ~=true~);if(~;if(@~I@l@t~;@vTc~false~\";if(~@hzgt" ascii
    $s14 = "~i=37629JU1~4,4101,4774,2380~E@sntJF~,5858,19,6496,2)~928,8831,3828,3)~J99~var @hyM@tJe;~@r@ikJF~(182,370,9954,6~eak;case 0Jd~JY" ascii
    $s15 = ";;var ~\"}JA~==falseJ`~(7589,95,1659~JA1~trueJY~;break;case ~)JL(~JJ@~=@urTk@g(\"0~))J[(~[@urTk@g(\"0~=trueJ`~@lv@m@k@xja~@p@m@t" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}