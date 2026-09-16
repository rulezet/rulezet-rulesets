rule TTP_XOR_QUAD_CurrentVersionRun_e59f {
  strings:
    $key_e59f = { b6 f0 [2] 92 fe [2] b9 d2 [2] 97 f0 [2] 83 eb [2] 8c f1 [2] 92 ec [2] 90 ed [2] 8b eb [2] 97 ec [2] 8b c3 }

  condition:
    any of them
}