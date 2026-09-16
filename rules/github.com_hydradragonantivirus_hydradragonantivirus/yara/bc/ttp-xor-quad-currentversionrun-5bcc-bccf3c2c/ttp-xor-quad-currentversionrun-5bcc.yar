rule TTP_XOR_QUAD_CurrentVersionRun_5bcc {
  strings:
    $key_5bcc = { 08 a3 [2] 2c ad [2] 07 81 [2] 29 a3 [2] 3d b8 [2] 32 a2 [2] 2c bf [2] 2e be [2] 35 b8 [2] 29 bf [2] 35 90 }

  condition:
    any of them
}