rule TTP_XOR_WriteProcessMemory_dbda {
  strings:
    $key_dbda = { 8c a8 [2] be 8a [2] b8 bf [2] 96 bf [2] a9 a3 }

  condition:
    any of them
}