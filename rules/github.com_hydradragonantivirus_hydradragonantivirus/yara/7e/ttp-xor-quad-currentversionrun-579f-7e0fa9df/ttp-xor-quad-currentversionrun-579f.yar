rule TTP_XOR_QUAD_CurrentVersionRun_579f {
  strings:
    $key_579f = { 04 f0 [2] 20 fe [2] 0b d2 [2] 25 f0 [2] 31 eb [2] 3e f1 [2] 20 ec [2] 22 ed [2] 39 eb [2] 25 ec [2] 39 c3 }

  condition:
    any of them
}