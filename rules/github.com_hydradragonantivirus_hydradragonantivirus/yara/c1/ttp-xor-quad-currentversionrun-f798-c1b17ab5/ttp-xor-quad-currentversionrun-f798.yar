rule TTP_XOR_QUAD_CurrentVersionRun_f798 {
  strings:
    $key_f798 = { a4 f7 [2] 80 f9 [2] ab d5 [2] 85 f7 [2] 91 ec [2] 9e f6 [2] 80 eb [2] 82 ea [2] 99 ec [2] 85 eb [2] 99 c4 }

  condition:
    any of them
}