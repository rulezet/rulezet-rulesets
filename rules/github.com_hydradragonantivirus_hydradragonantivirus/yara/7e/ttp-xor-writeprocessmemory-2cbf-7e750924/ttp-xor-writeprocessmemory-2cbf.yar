rule TTP_XOR_WriteProcessMemory_2cbf {
  strings:
    $key_2cbf = { 7b cd [2] 49 ef [2] 4f da [2] 61 da [2] 5e c6 }

  condition:
    any of them
}