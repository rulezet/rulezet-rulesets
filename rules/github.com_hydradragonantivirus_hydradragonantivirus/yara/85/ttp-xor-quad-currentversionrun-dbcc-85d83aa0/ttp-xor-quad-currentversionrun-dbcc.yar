rule TTP_XOR_QUAD_CurrentVersionRun_dbcc {
  strings:
    $key_dbcc = { 88 a3 [2] ac ad [2] 87 81 [2] a9 a3 [2] bd b8 [2] b2 a2 [2] ac bf [2] ae be [2] b5 b8 [2] a9 bf [2] b5 90 }

  condition:
    any of them
}