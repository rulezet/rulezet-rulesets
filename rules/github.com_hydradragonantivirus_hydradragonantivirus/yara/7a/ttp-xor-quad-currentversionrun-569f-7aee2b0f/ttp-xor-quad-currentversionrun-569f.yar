rule TTP_XOR_QUAD_CurrentVersionRun_569f {
  strings:
    $key_569f = { 05 f0 [2] 21 fe [2] 0a d2 [2] 24 f0 [2] 30 eb [2] 3f f1 [2] 21 ec [2] 23 ed [2] 38 eb [2] 24 ec [2] 38 c3 }

  condition:
    any of them
}