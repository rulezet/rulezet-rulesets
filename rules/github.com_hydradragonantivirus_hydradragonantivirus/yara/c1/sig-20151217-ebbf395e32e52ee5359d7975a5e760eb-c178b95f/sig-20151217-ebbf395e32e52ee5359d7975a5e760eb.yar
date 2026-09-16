rule sig_20151217_ebbf395e32e52ee5359d7975a5e760eb {
  meta:
    description = "datamaliciousorder - file 20151217_ebbf395e32e52ee5359d7975a5e760eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0336656f65fd2676f8a359e1128677bced5f75b88f93b337ff8af4bb4356a2eb"

  strings:
    $s1  = ".pow(Math.cos(555), 2) - 1)); while(true) { if(RAwpgQaVh[UrBhmBQuUPC] > hLJxq[UrBhmBQuUPC].length-(-209+308)/99) { break; } if (" ascii
    $s2  = "(Math.cos(858), 2) - 1)));} RAwpgQaVh[UrBhmBQuUPC]++;}UrBhmBQuUPC++;} return hyxZHqIdmtf}" fullword ascii
    $s3  = "function BIYNNUHgtrnkWKBwF(hLJxq){hyxZHqIdmtf= '';UrBhmBQuUPC=Math.round((Math.pow(Math.sin(44), 2) + Math.pow(Math.cos(44), 2) " ascii
    $s4  = "function BIYNNUHgtrnkWKBwF(hLJxq){hyxZHqIdmtf= '';UrBhmBQuUPC=Math.round((Math.pow(Math.sin(44), 2) + Math.pow(Math.cos(44), 2) " ascii
    $s5  = "- 1));while(true){if (UrBhmBQuUPC >= (3350+970)/720){break;}RAwpgQaVh[UrBhmBQuUPC]=Math.round((Math.pow(Math.sin(555), 2) + Math" ascii
    $s6  = "function WcvFpeE(DKqBykCnxqpNEdFQNacjeMjpBLxTcLSFnJhB) {return !ELjJzbrNFRN(VdZNINWMvvbgylM(DKqBykCnxqpNEdFQNacjeMjpBLxTcLSFnJhB" ascii
    $s7  = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s8  = "function lZAjozKXBSKtDro(XLKMMEEzERMVCgZzf,zwyVwlXgHacVZKkRBfwfQKQrUakdiDPbyD,eIhJfqZLbjmVVOgsLLblDhYwPtTZYSNfLHo){eval(XLKMMEEz" ascii
    $s9  = "function x(sqpYthUNEdfa,vioCVNrkWTeUpb){sqpYthUNEdfa.push(vioCVNrkWTeUpb);}" fullword ascii
    $s10 = "function WcvFpeE(DKqBykCnxqpNEdFQNacjeMjpBLxTcLSFnJhB) {return !ELjJzbrNFRN(VdZNINWMvvbgylM(DKqBykCnxqpNEdFQNacjeMjpBLxTcLSFnJhB" ascii
    $s11 = "function mMPcj(AmFtSWkRVio,StYWdYKLmDmkA,WoQgizqb){FIme=lxAaIRuvKKcnsnDzw(AmFtSWkRVio,StYWdYKLmDmkA);FekXE=FIme.toString(WoQgizq" ascii
    $s12 = "function uIPWXGbhQBOFyeohoshOXezWgSZZWuBqtOweZqfYLIJObWtVrbncMi(hRjBnVbqUGIrs,YhutWSUeNuCzPJ){ return EYDGWGU[FkFSfvfJ[mMPcj(hRj" ascii
    $s13 = "function uIPWXGbhQBOFyeohoshOXezWgSZZWuBqtOweZqfYLIJObWtVrbncMi(hRjBnVbqUGIrs,YhutWSUeNuCzPJ){ return EYDGWGU[FkFSfvfJ[mMPcj(hRj" ascii
    $s14 = "b);return FekXE;}" fullword ascii
    $s15 = "function ELjJzbrNFRN(gaITsGlqZRfiVS) {return isNaN(gaITsGlqZRfiVS);}" fullword ascii
    $s16 = "function mMPcj(AmFtSWkRVio,StYWdYKLmDmkA,WoQgizqb){FIme=lxAaIRuvKKcnsnDzw(AmFtSWkRVio,StYWdYKLmDmkA);FekXE=FIme.toString(WoQgizq" ascii
    $s17 = "function lxAaIRuvKKcnsnDzw(KLUuneBEKF,IdkMQEUxiU) {return parseInt(KLUuneBEKF,IdkMQEUxiU);}" fullword ascii
    $s18 = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s19 = "function lZAjozKXBSKtDro(XLKMMEEzERMVCgZzf,zwyVwlXgHacVZKkRBfwfQKQrUakdiDPbyD,eIhJfqZLbjmVVOgsLLblDhYwPtTZYSNfLHo){eval(XLKMMEEz" ascii
    $s20 = "function c(DBTyoEBbTHWIGy,mtOyDIMcZBGQv,hszdfVQZpAS) {DBTyoEBbTHWIGy[mtOyDIMcZBGQv]=hszdfVQZpAS;}" fullword ascii

  condition:
    uint16(0) == 0x6b46 and
    8 of them
}