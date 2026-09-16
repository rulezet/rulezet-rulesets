rule TTP_XOR_QUAD_CurrentVersionRun_f981 {
  strings:
    $key_f981 = { aa ee [2] 8e e0 [2] a5 cc [2] 8b ee [2] 9f f5 [2] 90 ef [2] 8e f2 [2] 8c f3 [2] 97 f5 [2] 8b f2 [2] 97 dd }

  condition:
    any of them
}