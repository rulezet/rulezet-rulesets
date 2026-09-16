rule DebuggerOutput__String: AntiDebug DebuggerOutput {
  meta:
    author    = "naxonez"
    reference = "https://github.com/naxonez/yaraRules"
    weight    = 1

  strings:
    $ = "OutputDebugString"

  condition:
    any of them
}