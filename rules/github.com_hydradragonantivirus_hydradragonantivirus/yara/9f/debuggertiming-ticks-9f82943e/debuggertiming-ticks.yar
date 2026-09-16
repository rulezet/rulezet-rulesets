rule DebuggerTiming__Ticks: AntiDebug DebuggerTiming {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = "GetTickCount"

  condition:
    any of them
}