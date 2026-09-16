rule TTP_XOR_QUAD_CurrentVersionRun_659f {
  strings:
    $key_659f = { 36 f0 [2] 12 fe [2] 39 d2 [2] 17 f0 [2] 03 eb [2] 0c f1 [2] 12 ec [2] 10 ed [2] 0b eb [2] 17 ec [2] 0b c3 }

  condition:
    any of them
}