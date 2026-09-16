rule TTP_XOR_QUAD_CurrentVersionRun_299c {
  strings:
    $key_299c = { 7a f3 [2] 5e fd [2] 75 d1 [2] 5b f3 [2] 4f e8 [2] 40 f2 [2] 5e ef [2] 5c ee [2] 47 e8 [2] 5b ef [2] 47 c0 }

  condition:
    any of them
}