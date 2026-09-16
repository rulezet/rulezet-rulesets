rule sig_20150909_5eb87329281980ff04986e5a4d9bba1c {
  meta:
    description = "datamaliciousorder - file 20150909_5eb87329281980ff04986e5a4d9bba1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efad4aff3aa7f874b8981c97c84c577d98c3c5764e01eb55500d8fbe6dd8a7f4"

  strings:
    $x1  = "var kpfLayerCounter=0;var eventOverallDuration=0;var KPFPlaybackController=Class.create({initialize:function(b,a){this.domNode=a" ascii
    $s2  = "else{a=v.naturalWidth;c=v.naturalHeight;if(v.src.indexOf(\"KNTransitionSlide_Black.png\")!=-1){a=gShowController.script.slideWid" ascii
    $s3  = "rototype.Browser.Gecko||navigator.userAgent.lastIndexOf(\"Chrome/\")>0)){return\"translateZ(\"+-c.scalar+\"px)\"}else{return\"tr" ascii
    $s4  = "ames.push({keyframe:t-f,keyName:\"zPosition\",value:u,timingFunction:\"linear\"})}r.keyframes.push({keyframe:t,keyName:\"zPositi" ascii
    $s5  = "ar h=0,b=d.length;h<b;h++){d[h].effects=this.processEffects(d[h].effects)}return d},renderEffects:function(b){var k=[];for(var e" ascii
    $s6  = "tX:y[0],pointY:y[1]},fillMode:\"forwards\",beginTime:o+a.beginTime+(v/B)*a.duration,duration:1/B*a.duration,timingFunction:\"lin" ascii
    $s7  = "yers[a],f.layers[a])}}},processEffects:function(a){var d=[];for(var h=0;h<a.length;h++){var m=a[h];if(m.type===\"actionBuild\"){" ascii
    $s8  = "ginTime:t+v/B*b,duration:1/B*b,timingFunction:\"linear\"};break}this.addAction(w,C)}}else{if(C.keyTimes){var s=C.keyTimes.length" ascii
    $s9  = ":t,keyName:\"position\",value:o,timingFunction:\"linear\"});r.keyframes.push({keyframe:100,keyName:\"position\",value:o,timingFu" ascii
    $s10 = "alue:p.from,timingFunction:\"linear\"});r.keyframes.push({keyframe:100,keyName:\"zPosition\",value:p.to,timingFunction:\"linear" ascii
    $s11 = "Value(x,j,p.from,false);if(x.isMagicMove){u={pointX:0,pointY:0}}r.keyframes.push({keyframe:0,keyName:\"position\",value:u,timing" ascii
    $s12 = "InitialKeyframeValue(x,j,p.from,true);r.keyframes.push({keyframe:0,keyName:\"zPosition\",value:u,timingFunction:\"linear\"});r.k" ascii
    $s13 = "h({keyframe:n,keyName:j,value:e,timingFunction:\"linear\"});r.keyframes.push({keyframe:t-f,keyName:j,value:e,timingFunction:\"li" ascii
    $s14 = "ush({keyframe:this.roundNum(m),keyName:j,value:s,timingFunction:\"linear\"});r.keyframes.push({keyframe:100,keyName:j,value:s,ti" ascii
    $s15 = "ngFunction:\"linear\"})}}},insertInitialKeyframes:function(b,c,d,a){b.keyframes.push({keyframe:0,keyName:d,value:a,timingFunctio" ascii
    $s16 = "\"linear\"});b.keyframes.push({keyframe:c,keyName:d,value:a,timingFunction:\"linear\"})},anchorPointOffset:function(c,e){var a={" ascii
    $s17 = "artKeyframe)-f,keyName:j,value:s,timingFunction:\"linear\"})}var a=this.createTimingFunctionForAction(p);r.keyframes.push({keyfr" ascii
    $s18 = "nction:\"linear\"});r.keyframes.push({keyframe:t-f,keyName:\"position\",value:u,timingFunction:\"linear\"})}r.keyframes.push({ke" ascii
    $s19 = "d.movieId))}}if(isChrome&&d.animationInfo.name===\"apple:doorway\"){if(d.layers.length===0&&d.contentsRect.x===0&&d.contentsRect" ascii
    $s20 = "yId(\"layer\"+j.layerId);var k=window.getComputedStyle(b,null);var l=k.getPropertyValue(kTransformPropertyName);var f=parseTrans" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}