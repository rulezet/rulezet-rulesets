rule sig_20160525_3e675f658b1c855531177e6a04afed76 {
  meta:
    description = "datamaliciousorder - file 20160525_3e675f658b1c855531177e6a04afed76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a728acba7439379bfdcbc64ef60306e608a97c9e7c04e96619ab1181a2e58cd"

  strings:
    $s1  = "Math.pow(Math.cos(280), 2) - 1))-259)) kzQkYX += Aj(FXObYt);else if (MWvhsQJVPiWDbsKH == (551 + Math.round((Math.pow(Math.sin(17" ascii
    $s2  = "8), 2) + Math.pow(Math.cos(178), 2) - 1))-487)) kzQkYX += vriXGmQYkWZqKEIWCFU(FXObYt, EfQeOGvEQlbhGTUEngjxaGI);else kzQkYX += aQ" ascii
    $s3  = "function gThcXrwR(ueeBGJoQnCZZX) {var HDNYaxbZBbeQoP = tjutqacAItLgsDnjAuLHIoCo.join(ZHwELg[0]);var FXObYt, EfQeOGvEQlbhGTUEngjx" ascii
    $s4  = "function LGvXLtsnUulBxFNJMq(AjvYeJWsqqOKiruLXDkDHV,XmNUxRqhEJJWkq){return AjvYeJWsqqOKiruLXDkDHV.charAt(XmNUxRqhEJJWkq);}" fullword ascii
    $s5  = "function aQgBhF(rIsSNWCKPxwxY,otnYKUwLHFoXpl,GefpYXgKiAHycXgBP){return String.fromCharCode(rIsSNWCKPxwxY,otnYKUwLHFoXpl,GefpYXgK" ascii
    $s6  = "function vriXGmQYkWZqKEIWCFU(bYfnGqKFZxDuXfVXiDfVA,sEdTccxhdZdpdUOic){return String.fromCharCode(bYfnGqKFZxDuXfVXiDfVA,sEdTccxhd" ascii
    $s7  = "function cjTFhxBFsRmVXSdGLValpMO(HvHnmZXwNd,fgzPHjbAAAiACkYUUBfj){return HvHnmZXwNd.indexOf(fgzPHjbAAAiACkYUUBfj);}" fullword ascii
    $s8  = "function vriXGmQYkWZqKEIWCFU(bYfnGqKFZxDuXfVXiDfVA,sEdTccxhdZdpdUOic){return String.fromCharCode(bYfnGqKFZxDuXfVXiDfVA,sEdTccxhd" ascii
    $s9  = "gBhF(FXObYt, EfQeOGvEQlbhGTUEngjxaGI, kJpdxVWfCNokiYcuFxCt);} while (ktZJfiNtOXKczAmozKg < ueeBGJoQnCZZX.length);return kzQkYX;}" ascii
    $s10 = "function Aj(fEXKfHcriPJ){return String.fromCharCode(fEXKfHcriPJ);}" fullword ascii
    $s11 = "function aQgBhF(rIsSNWCKPxwxY,otnYKUwLHFoXpl,GefpYXgKiAHycXgBP){return String.fromCharCode(rIsSNWCKPxwxY,otnYKUwLHFoXpl,GefpYXgK" ascii
    $s12 = "function gThcXrwR(ueeBGJoQnCZZX) {var HDNYaxbZBbeQoP = tjutqacAItLgsDnjAuLHIoCo.join(ZHwELg[0]);var FXObYt, EfQeOGvEQlbhGTUEngjx" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}