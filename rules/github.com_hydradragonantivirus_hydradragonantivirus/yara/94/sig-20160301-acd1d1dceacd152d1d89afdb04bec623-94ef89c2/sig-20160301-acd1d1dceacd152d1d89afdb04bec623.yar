rule sig_20160301_acd1d1dceacd152d1d89afdb04bec623 {
  meta:
    description = "datamaliciousorder - file 20160301_acd1d1dceacd152d1d89afdb04bec623.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e032759d9a8d67728a5e7aaf3325ff9f052fe88628224681c8a24ee913f5818f"

  strings:
    $s1 = "riskCommunication = (((10 | 2) - (([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]]))), this);" fullword ascii
    $s2 = "while(encyclopediaMigrate[(\"\\u0061\\u0064\\u0061\\u0070\" + \"tat\" + \"\\u0069\\u006f\" + \"n\", \"re\\u0073\\u0069\\u0064\" " ascii
    $s3 = "006fmm\" + \"i\" + \"tt\\u0065\\u0065\", \"\\u006dag\\u0069\" + \"\\u0063\", function String.prototype.radiationLecture() {" fullword ascii
    $s4 = "while(encyclopediaMigrate[(\"\\u0061\\u0064\\u0061\\u0070\" + \"tat\" + \"\\u0069\\u006f\" + \"n\", \"re\\u0073\\u0069\\u0064\" " ascii
    $s5 = "encyclopediaMigrate = riskCommunication[(\"re\\u0067\\u0072\\u0065\\u0073\" + \"s\\u0069\\u006f\\u006e\", \"\\u0065v\\u006f\\u00" ascii
    $s6 = "} catch(agentPreamble) {};" fullword ascii

  condition:
    uint16(0) == 0x6972 and
    all of them
}