rule TTP_XOR_QUAD_CurrentVersionRun_f793 {
  strings:
    $key_f793 = { a4 fc [2] 80 f2 [2] ab de [2] 85 fc [2] 91 e7 [2] 9e fd [2] 80 e0 [2] 82 e1 [2] 99 e7 [2] 85 e0 [2] 99 cf }

  condition:
    any of them
}