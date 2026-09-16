rule TTP_XOR_QUAD_CurrentVersionRun_b898 {
  strings:
    $key_b898 = { eb f7 [2] cf f9 [2] e4 d5 [2] ca f7 [2] de ec [2] d1 f6 [2] cf eb [2] cd ea [2] d6 ec [2] ca eb [2] d6 c4 }

  condition:
    any of them
}