rule TTP_XOR_QUAD_CurrentVersionRun_ffe2 {
  strings:
    $key_ffe2 = { ac 8d [2] 88 83 [2] a3 af [2] 8d 8d [2] 99 96 [2] 96 8c [2] 88 91 [2] 8a 90 [2] 91 96 [2] 8d 91 [2] 91 be }

  condition:
    any of them
}