rule TTP_XOR_QUAD_CurrentVersionRun_f99c {
  strings:
    $key_f99c = { aa f3 [2] 8e fd [2] a5 d1 [2] 8b f3 [2] 9f e8 [2] 90 f2 [2] 8e ef [2] 8c ee [2] 97 e8 [2] 8b ef [2] 97 c0 }

  condition:
    any of them
}