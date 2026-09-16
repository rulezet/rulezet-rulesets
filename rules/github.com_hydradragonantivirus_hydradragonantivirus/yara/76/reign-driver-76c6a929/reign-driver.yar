rule Reign_Driver {
    meta:
        info = "Reign Driver Component (32-bit)"

    strings:
                        $config_block_padding = {c739f2c8ee70ebc9cf31fac0e678d3f1f709c2f8de40dbf9ff01caf0}

    condition:
        $config_block_padding
}