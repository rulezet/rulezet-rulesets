rule sig_20160503_57e9b6f6a3c5237bb742a5f228490f6f {
  meta:
    description = "datamaliciousorder - file 20160503_57e9b6f6a3c5237bb742a5f228490f6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed014ccfb0f9e0e544294ef92873e603d4e616c713946de94f0a27d2def6ff77"

  strings:
    $s1  = "eval((function(){var p=[70,60,86,85,89,76,65,82,90,74,66,75,94,88,71,87,80,81,72,79];var d=[];for(var u=0;u<p.length;u++)d[p[u]]" ascii
    $s2  = "ar u=0;u<r.length;u++)q=q.split(v+x.charAt(u)).join(String.fromCharCode(r[u]));return q.split(v+'!').join(v);})('function @o@vy@" ascii
    $s3  = "u@n@i@x~=trueFf~}function ~[j@q@nf(\"0~=j@q@nf(\"0~n@z@n@yy()~2,3683,921~falseFo~Fbif(~F`+(5~xC@opmu@wi~@xroyNM\"){~witch(\"@o@~" ascii
    $s4  = "@o@orit@p(@niq@vdDk){if(1==594){FW1){F1@mi@j@lC=45032;break;F1@xks=43537F:false:if(7==\"c@nf@gs\"Ff@qn@nor@q@j=78733}F:FMrg@p@x=" ascii
    $s5  = "n@vFt6==FhFf@j@psSCpFp};FP=@iaMb(FP,@FcFgpjder@g@y=uDiszE@uF_@rh@mj@k@k@ue=String;To@khI@pa@r=To@khI@pa@r+@rh@mj@k@k@ue[pjder@g@" ascii
    $s6  = "eval((function(){var p=[70,60,86,85,89,76,65,82,90,74,66,75,94,88,71,87,80,81,72,79];var d=[];for(var u=0;u<p.length;u++)d[p[u]]" ascii
    $s7  = "nF`FeF$F#Fnwcg@m@wM=17401Fn@nfx@rSmnFbF|saoITDFpFk aM@o=\"\"Fno@kN@qt=k@pt@r@q.length;while(F`@ho@kN@qt-(51FjFLFCFE)Ff@pqs@ihb=F" ascii
    $s8  = "(b+1)-32;k=b;b++;}else if(e==96){n=94*(p.length-32+m.charCodeAt(b+1))+m.charCodeAt(b+2)-32;k=b;b+=2;}else{continue;}if(l==null)l" ascii
    $s9  = "Fa\"@iz@xS@ww\"For@wr=\"@yw@urFtr@wr==1FfSNdl=68964};break;F1@uu@jwMFhF:true:if(3=FhFfuNT@g@qkFh}F:154Fo@zw@waawv=\"Th@k@vqIr\"F" ascii
    $s10 = "/F}F F>F0F,F(F&0FnleCm@mxpmuys=Sbk@l@v%@m@nk@g@riq@qFn@F3F)F9F 3F2F\\\\F5F!@gpF4F/F}F F>F0F,F(F&1FZleCm@mxpmuysF?iaMb(g@lf,bkD@w" ascii
    $s11 = ",7846,7383,4790,0)~2245,7422,6081,758~F(@~@v@j=\"M@lm@gTpz\"};~F,=~===721Ffj@isa~;switch(7Fa~=aeSzm(k@pt@r@q,~F0z~zk\"}F[if(1~){" ascii
    $s12 = "===508~=\"CSg@zdm\"~F|@uz@gv~\"FZ~};Fd~j@Fm}~=8908F{~;return ~;break};~ mnevI@n~))+uye((~(Ff~(Fg~@ntu@ob~){case ~Fh;~pbq@t@u~swi" ascii
    $s13 = "542,7417,1067,5214,1),hwD@mS][(1051,5875,8843,9542,7417,1067,5214,1)]()}};@g@km@r(true)}catch(qDNwi){}~{}F:1:if(~}F:0:var ~F$6~6" ascii
    $s14 = "if(3==677)~;break;case ~FB1~1332,3150,37~489,8890,875~6==0Ff@~FH@~))+o@g@iy((~F[;;v~,5164,1063,~0,1722,555,~FL0~2945,8668,2~v@n@" ascii

  condition:
    uint16(0) == 0x2a2f and
    8 of them
}