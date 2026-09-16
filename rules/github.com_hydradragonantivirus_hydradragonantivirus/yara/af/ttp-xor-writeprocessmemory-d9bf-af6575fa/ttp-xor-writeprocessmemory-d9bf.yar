rule TTP_XOR_WriteProcessMemory_d9bf {
  strings:
    $key_d9bf = { 8e cd [2] bc ef [2] ba da [2] 94 da [2] ab c6 }

  condition:
    any of them
}