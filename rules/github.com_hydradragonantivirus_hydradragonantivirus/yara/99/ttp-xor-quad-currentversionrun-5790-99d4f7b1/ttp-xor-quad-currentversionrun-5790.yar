rule TTP_XOR_QUAD_CurrentVersionRun_5790 {
  strings:
    $key_5790 = { 04 ff [2] 20 f1 [2] 0b dd [2] 25 ff [2] 31 e4 [2] 3e fe [2] 20 e3 [2] 22 e2 [2] 39 e4 [2] 25 e3 [2] 39 cc }

  condition:
    any of them
}