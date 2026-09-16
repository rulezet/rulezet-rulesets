rule sig_20160503_6ac911100138c774a681f94228d5b29d {
  meta:
    description = "datamaliciousorder - file 20160503_6ac911100138c774a681f94228d5b29d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a9f0658babf7f60302034c2ef78df6a10912eeed78922d83807ee1c4f2f1eb8"

  strings:
    $s1  = "eval((function(){var t=[80,94,71,65,66,60,70,85,87,72,90,86,88,74,76,75,82,79,89,81];var l=[];for(var x=0;x<t.length;x++)l[t[x]]" ascii
    $s2  = "ar x=0;x<q.length;x++)f=f.split(y+c.charAt(x)).join(String.fromCharCode(q[x]));return f.split(y+'!').join(y);})('function k@i@wa" ascii
    $s3  = "eval((function(){var t=[80,94,71,65,66,60,70,85,87,72,90,86,88,74,76,75,82,79,89,81];var l=[];for(var x=0;x<t.length;x++)l[t[x]]" ascii
    $s4  = "E=\"Nn@kx@u\";bP @gTk@j@inPN@gTk@j@in=PPPt@ieIPlPJP^P<27^&22030^$@gnr@ua@zIb,@o@rs@z@g,false)P{P6Px:PFPEI@vy@PIP@P1falPCPBP93;P^" ascii
    $s5  = "fv@s==0){};break}PDuy@z(PfkzEvtE=[(141^!44,5145,1),@jctive@s@xbject,(9827,171^!22,2)][1]P[kzEvtEPDg@kN(dfeggPfd@jE=uy@z()PZ3)Pi0" ascii
    $s6  = "10~a@sd@kpv=~46,1856,6~))+sDs((~P{tch(~;return ~@me@jaIx~Pc@~So@wNvlj~=Ph+~s@j@ueN(~v@v@jMi(~Pf@~(Pg~ \"nx@o@~Pr@~){Pt~)Pr~n@swz" ascii
    $s7  = "vT@yNPwz,Tj@g,jsIv,o@v@t@r@ou@j,@r@g@jIq,ejkS,iI@mc@wu,bM@qwy,hike,@v@ky@jch]P[olazdDI[@n@uDpNf]PDnzmanm@q(Pfi@vEDc@mq=@Pww@qhDz" ascii
    $s8  = "@r~978,9199,9~PX9~r==613){va~;break};;;~572,5868,3~P[@~\"P[~=truePu~===Px){~=Pj){~};break};~==1Pf~@n@qpkM()~)P[~w@qCsmt@i~@uwp@j" ascii
    $s9  = "35,7241,0)~f@rk@rT@um=24829;br~;P>1:var ~P);~P>712:var~ f@rk@rT@um=24829;~vP. ~ @rDD=\"l@z@y@jq\"}~ie@r=Px;break};~))+@Pww@qhDz(" ascii
    $s10 = "W\"\"Peq@sI=@Pwm@ru.length;while(Ph@l@q@sI-(P?)PfxIM=(41P\"PrEm@gIui@icP_P7Prbpe=nP!Em@gIui@ic)Pegxd@zu=nP!Ph+(P?)Pgr@tC=nP!Ph);" ascii
    $s11 = "(m+1)-32;i=m;m++;}else if(b==96){u=94*(t.length-32+v.charCodeAt(m+1))+v.charCodeAt(m+2)-32;i=m;m+=2;}else{continue;}if(e==null)e" ascii
    $s12 = "~{case ~=false~\":Pt~=Px}~{switc~7510,8~rr@k@v~=g@kN(~021\")]~;Pt~zanf@~var ~;if(~0000~t@s@~true~0040~0210~;swi~:if(~0600~0200~6" ascii
    $s13 = "};~);@k@zg@v@sh~PD@~[sx@t@ub(\"0~=sx@t@ub(\"0~break;case ~7955,7443,2~r l@qt=Px~PIr~biI@r=\"@v@s~se:Pt@q@r~}function ~Pj;if(~PtI" ascii
    $s14 = "@zbd@mhzw=64287;~P0l~lul@gg===1){var~P3@~@gg=38877Puv~};P>~h(false){case~yTvPkvlul~IvP<~P:I~tch(1)Pi~(2879,332,1)~PBq~q@y\";brea" ascii
    $s15 = "812,8460,843,5)Pu@zdp){[(5096,9228,1),rg@mT@n][(5096,9228,1)]()}}catch(hTzT@w@s){}~reak;case true:Pt~y@p@tESk(@Pwm@ru,~61,925,52" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}