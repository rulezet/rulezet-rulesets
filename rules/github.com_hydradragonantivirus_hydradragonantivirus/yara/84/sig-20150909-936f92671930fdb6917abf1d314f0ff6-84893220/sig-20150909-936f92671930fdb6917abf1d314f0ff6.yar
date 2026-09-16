rule sig_20150909_936f92671930fdb6917abf1d314f0ff6 {
  meta:
    description = "datamaliciousorder - file 20150909_936f92671930fdb6917abf1d314f0ff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "812c17968eeee6f94e111d0b31b84689910c6053b848de89ba6f2a58ae0a7637"

  strings:
    $s1  = "var kTouchStartEventName=\"touchstart\";var kTouchMoveEventName=\"touchmove\";var kTouchEndEventName=\"touchend\";var kTouchCanc" ascii
    $s2  = "s.swipeFingerCount+\" finger swipe is complete.\");var h=a.changedTouches[0];var m=document.viewport.getDimensions();var e=m.wid" ascii
    $s3  = "er_HandleTouchStartEvent,\"- this.swipeFingerCount:\"+this.swipeFingerCount)}}},handleTouchMoveEvent:function(a){if(this.prevent" ascii
    $s4  = "handleTouchCancelEvent.bind(this));document.observe(kGestureStartEventName,this.handleGestureStartEvent.bind(this));document.obs" ascii
    $s5  = "kAreaTop){debugMessage(kDebugTouchController_IsTouchWithinTrackArea,\"- nope, y < top\");return false}if(a.clientY>this.trackAre" ascii
    $s6  = "ouchEndEvent,\"-  it's a \"+this.swipeFingerCount+\" finger swipe in the \"+n+\" direction\");document.fire(kSwipeEvent,{directi" ascii
    $s7  = ".clientX;this.swipeStartY=a.clientY}else{debugMessage(kDebugTouchController_HandleTouchStartEvent,\"- but it is outside of the t" ascii
    $s8  = "s.trackAreaLeft){debugMessage(kDebugTouchController_IsTouchWithinTrackArea,\"- nope, x < left\");return false}if(a.clientX>this." ascii
    $s9  = "roller_IsTouchWithinTrackArea,\"- yes it is!\");return true},handleTouchStartEvent:function(b){debugMessage(kDebugTouchControlle" ascii
    $s10 = "ack area\")}}else{debugMessage(kDebugTouchController_HandleTouchStartEvent,\"- this is a subsequent finger down event. update fi" ascii
    $s11 = "==false){debugMessage(kDebugTouchController_IsTouchWithinTrackArea,\"- nope, tracking is disabled\");return false}if(a.clientX<t" ascii
    $s12 = "ottom){debugMessage(kDebugTouchController_IsTouchWithinTrackArea,\"- nope, y > bottom\");return false}debugMessage(kDebugTouchCo" ascii
    $s13 = "}}if(l){debugMessage(kDebugTouchController_HandleTouchEndEvent,\"-  it's a \"+this.swipeFingerCount+\" finger tap\");if(this.tap" ascii
    $s14 = "ackAreaRight){debugMessage(kDebugTouchController_IsTouchWithinTrackArea,\"- nope, x > right\");return false}if(a.clientY<this.tr" ascii
    $s15 = "th.abs(i);var o=new Date();var q=o-this.swipeStartTime;var l=false;var p=false;var f=400;var j=20;if(q<f){debugMessage(kDebugTou" ascii
    $s16 = "rve(kTouchStartEventName,this.handleTouchStartEvent.bind(this));document.observe(kTouchMoveEventName,this.handleTouchMoveEvent.b" ascii
    $s17 = "leTouchEndEvent,\"-  false alarm. swipe has already ended.\")}},handleTouchCancelEvent:function(a){debugMessage(kDebugTouchContr" ascii
    $s18 = "erve(kGestureEndEventName,this.handleGestureEndEvent.bind(this));this.swipeInProgress=false;this.swipeFingerCount=0;this.swipeSt" ascii
    $s19 = "his.enableTouchTracking=true},setTouchTrackingEnabled:function(a){this.enableTouchTracking=a},setTrackArea:function(d,c,b,a){deb" ascii
    $s20 = "(a)){debugMessage(kDebugTouchController_HandleTouchStartEvent,\"- start tracking a swipt event...\");if(this.preventDefault){b.p" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}