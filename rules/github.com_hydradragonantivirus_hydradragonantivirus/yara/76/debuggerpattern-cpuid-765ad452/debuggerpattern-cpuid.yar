rule DebuggerPattern__CPUID: AntiDebug DebuggerPattern {
  meta:
    weight    = 1
    Author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

  strings:
    $ = { 0F A2 }

  condition:
    any of them
}