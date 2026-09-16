rule TTP_XOR_QUAD_CurrentVersionRun_ffe0 {
  strings:
    $key_ffe0 = { ac 8f [2] 88 81 [2] a3 ad [2] 8d 8f [2] 99 94 [2] 96 8e [2] 88 93 [2] 8a 92 [2] 91 94 [2] 8d 93 [2] 91 bc }

  condition:
    any of them
}