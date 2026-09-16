rule TTP_XOR_QUAD_CurrentVersionRun_f982 {
  strings:
    $key_f982 = { aa ed [2] 8e e3 [2] a5 cf [2] 8b ed [2] 9f f6 [2] 90 ec [2] 8e f1 [2] 8c f0 [2] 97 f6 [2] 8b f1 [2] 97 de }

  condition:
    any of them
}