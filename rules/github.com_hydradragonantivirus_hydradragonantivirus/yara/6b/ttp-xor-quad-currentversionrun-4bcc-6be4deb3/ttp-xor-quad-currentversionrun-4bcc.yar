rule TTP_XOR_QUAD_CurrentVersionRun_4bcc {
  strings:
    $key_4bcc = { 18 a3 [2] 3c ad [2] 17 81 [2] 39 a3 [2] 2d b8 [2] 22 a2 [2] 3c bf [2] 3e be [2] 25 b8 [2] 39 bf [2] 25 90 }

  condition:
    any of them
}