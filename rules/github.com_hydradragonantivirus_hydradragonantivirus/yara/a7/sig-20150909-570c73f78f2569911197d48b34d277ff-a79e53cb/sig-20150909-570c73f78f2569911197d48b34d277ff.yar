rule sig_20150909_570c73f78f2569911197d48b34d277ff {
  meta:
    description = "datamaliciousorder - file 20150909_570c73f78f2569911197d48b34d277ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "804f3d0fb6dfbb0773a2f6f1906656da3305e02907f4a923e2b3aa82ba390e17"

  strings:
    $s1  = "nerHTML=b}else{this.slideNumberLabel.innerHTML=\"Press Return to go to slide:\"}this.slideNumberDigit=document.createElement(\"d" ascii
    $s2  = "var SlideNumberController=Class.create({initialize:function(a,b){this.domNode=a;this.width=120;this.height=110;this.slideNumberL" ascii
    $s3  = "yle.display=\"block\";this.domNode.style.opacity=1},hide:function(){this.isShowing=false;this.domNode.style.display=\"none\";thi" ascii
    $s4  = ".domNode.style.top=a+\"px\"},setSlideNumber:function(a){this.slideNumberDigit.innerHTML=a},show:function(a){this.isShowing=true;" ascii
    $s5  = "pendChild(this.slideNumberDigit);this.isShowing=false},setPosition:function(b,a){this.domNode.style.left=b+\"px\";this.domNode.s" ascii
    $s6  = "le.top=a+\"px\"},setSlideNumber:function(a){this.slideNumberDigit.innerHTML=a},show:function(){this.isShowing=true;this.domNode." ascii
    $s7  = "is.domNode.style.display=\"block\";this.domNode.style.opacity=1},hide:function(){this.isShowing=false;this.domNode.style.display" ascii
    $s8  = "s.domNode.appendChild(this.slideNumberDigit);this.isShowing=false},setPosition:function(b,a){this.domNode.style.left=b+\"px\";th" ascii
    $s9  = "mNode.style.opacity=0}});var SlideNumberDisplay=Class.create({initialize:function(a){this.domNode=a;this.width=100;this.height=1" ascii
    $s10 = "var SlideNumberController=Class.create({initialize:function(a,b){this.domNode=a;this.width=120;this.height=110;this.slideNumberL" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}