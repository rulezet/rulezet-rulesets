rule TTP_XOR_QUAD_CurrentVersionRun_769f {
  strings:
    $key_769f = { 25 f0 [2] 01 fe [2] 2a d2 [2] 04 f0 [2] 10 eb [2] 1f f1 [2] 01 ec [2] 03 ed [2] 18 eb [2] 04 ec [2] 18 c3 }

  condition:
    any of them
}