rule TTP_XOR_QUAD_CurrentVersionRun_6bcc {
  strings:
    $key_6bcc = { 38 a3 [2] 1c ad [2] 37 81 [2] 19 a3 [2] 0d b8 [2] 02 a2 [2] 1c bf [2] 1e be [2] 05 b8 [2] 19 bf [2] 05 90 }

  condition:
    any of them
}