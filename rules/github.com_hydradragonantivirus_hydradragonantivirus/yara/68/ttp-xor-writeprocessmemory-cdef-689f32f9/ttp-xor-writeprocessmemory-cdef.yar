rule TTP_XOR_WriteProcessMemory_cdef {
  strings:
    $key_cdef = { 9a 9d [2] a8 bf [2] ae 8a [2] 80 8a [2] bf 96 }

  condition:
    any of them
}