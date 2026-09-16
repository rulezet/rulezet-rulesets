rule sig_20150909_7d856ad2bec43b9aa4e9919b7804c1a3 {
  meta:
    description = "datamaliciousorder - file 20150909_7d856ad2bec43b9aa4e9919b7804c1a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f45437168a14fc80c5963c21c38fa40f11af08a57189b52bd33a185557ddad4"

  strings:
    $x1  = "var SlideManager=Class.create({initialize:function(c){this.header=c.header;this.slides={};for(var a=0,b=this.header.slideList.le" ascii
    $s2  = ",c);document.head.appendChild(a)}else{new Ajax.Request(c,{method:\"get\",onSuccess:this.slideDidDownload.bind(this,b),onFailure:" ascii
    $s3  = "is.slideDidNotDownload.bind(this,b)})}},slideDidDownload:function(c,b,a){if(a){c=b.name;this.slides[c].script=b.json;this.slides" ascii
    $s4  = "ngth;a<b;a++){this.slides[this.header.slideList[a]]={downloaded:false,script:{},retry:0}}},getSlides:function(d,b){for(var a=0,c" ascii
    $s5  = "l_slide=(function(d){this.slideDidDownload(null,d,true)}).bind(this)}var a=document.createElement(\"script\");a.setAttribute(\"s" ascii
    $s6  = "[c].originalScript=JSON.parse(JSON.stringify(b.json))}else{this.slides[c].script=JSON.parse(b.responseText);this.slides[c].origi" ascii
    $s7  = "nload:function(){var a=arguments[0];if(arguments[1].status!=200){if(this.slides[a].retry<1){this.downloadSlide(a);this.slides[a]" ascii
    $s8  = ".retry++}else{document.fire(kSlideDidNotDownloadEvent,{id:a})}}}});" fullword ascii
    $s9  = "b+\".json\";if(window.location.protocol===\"file:\"){c=c+\"p\";if(window.local_slide==null||window.local_slide==undefined){windo" ascii
    $s10 = "wnloadSlides:function(c){for(var a=0,b=c.length;a<b;a++){this.downloadSlide(c[a])}},downloadSlide:function(b){var c=\"../\"+b+\"" ascii
    $s11 = "var SlideManager=Class.create({initialize:function(c){this.header=c.header;this.slides={};for(var a=0,b=this.header.slideList.le" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}