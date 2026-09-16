rule sig_20151214_9f5e84ebe6c66cea6e71cc74c315ff01 {
  meta:
    description = "datamaliciousorder - file 20151214_9f5e84ebe6c66cea6e71cc74c315ff01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afc06b55e385c525cdcc6892f5282fd4e3f98b867640dacc883733b5fbddabbc"

  strings:
    $s1  = "Math.pow(Math.cos(691), 2) - 1)); while(true) { if(jQpYNmgov[uXQOiJWOjBJ] > HFygg[uXQOiJWOjBJ].length-(486+273)/759) { break; } " ascii
    $s2  = "h.pow(Math.cos(292), 2) - 1)));} jQpYNmgov[uXQOiJWOjBJ]++;}} return DvVrZWlvMBf}" fullword ascii
    $s3  = "function A(iHtZQZwUgsvo,comRRLqgIUgjeH){iHtZQZwUgsvo.push(comRRLqgIUgjeH);}function o9(nOdCLWMiqmglJRNq){if(lXbNGri(nOdCLWMiqmgl" ascii
    $s4  = "function LYzsvSNrikBXgNDCz(HFygg){DvVrZWlvMBf= H[1770];for(uXQOiJWOjBJ=Math.round((Math.pow(Math.sin(610), 2) + Math.pow(Math.co" ascii
    $s5  = "function LYzsvSNrikBXgNDCz(HFygg){DvVrZWlvMBf= H[1770];for(uXQOiJWOjBJ=Math.round((Math.pow(Math.sin(610), 2) + Math.pow(Math.co" ascii
    $s6  = "JRNq)) {return (String.fromCharCode(nOdCLWMiqmglJRNq) + String.fromCharCode((69664+804)/892));}}" fullword ascii
    $s7  = "function A(iHtZQZwUgsvo,comRRLqgIUgjeH){iHtZQZwUgsvo.push(comRRLqgIUgjeH);}function o9(nOdCLWMiqmglJRNq){if(lXbNGri(nOdCLWMiqmgl" ascii
    $s8  = "function lXbNGri(aWueFpJZXctHIcRJKyCxvlgZGzVrSXvvXhLf) {return !isNaN(parseFloat(aWueFpJZXctHIcRJKyCxvlgZGzVrSXvvXhLf)) && isFin" ascii
    $s9  = "function lXbNGri(aWueFpJZXctHIcRJKyCxvlgZGzVrSXvvXhLf) {return !isNaN(parseFloat(aWueFpJZXctHIcRJKyCxvlgZGzVrSXvvXhLf)) && isFin" ascii
    $s10 = "var H=new Array();" fullword ascii
    $s11 = "function kjmTuFoNDVK(jxqAjUoK,ySpxDw){return jxqAjUoK.split(ySpxDw)}" fullword ascii
    $s12 = "function BAdqOEiCIrfqixZ(flUjzBZVcvnXWwKci){eval(flUjzBZVcvnXWwKci)}" fullword ascii
    $s13 = " AtAes;}function BAdqOEiCIrfqixZ(flUjzBZVcvnXWwKci,mLdzvLApehPonTMHMrqqoNJhBfFlhbajwR,NuUmcczvNbuwMEzaqOlWkGIqvcLBmaceeNu){eval(" ascii
    $s14 = "function fePlqyIfXghaLTyrsCrerTHTvpZdkBfaEKyGSFsvNeWatCaRhtisHn(GQcBWRqtISrLX,WapAbpgrZePiTl){ return vuKjzUD[hLatdFyb[uJIip(GQc" ascii
    $s15 = "function uJIip(eqwUCErmXLA,HrHdAEWCAaMde,vrQSQxvw){xDGs=parseInt(eqwUCErmXLA,HrHdAEWCAaMde);AtAes=xDGs.toString(vrQSQxvw);return" ascii
    $s16 = "function uJIip(eqwUCErmXLA,HrHdAEWCAaMde,vrQSQxvw){xDGs=parseInt(eqwUCErmXLA,HrHdAEWCAaMde);AtAes=xDGs.toString(vrQSQxvw);return" ascii
    $s17 = "function fePlqyIfXghaLTyrsCrerTHTvpZdkBfaEKyGSFsvNeWatCaRhtisHn(GQcBWRqtISrLX,WapAbpgrZePiTl){ return vuKjzUD[hLatdFyb[uJIip(GQc" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}