rule warning_activex_exec {
    meta:
        is_exploit = false
        is_warning = true
        is_feature = true
        rank = 8
        revision = "3"
        date = "Oct 11 2017"
        author = "@tylabs"
	release = "lite"
        copyright = "QuickSand.io (c) Copyright 2015, 2017. All rights reserved."
        tlp = "white"
        sigtype = "cryptam_exploit"
        desc = "ActiveX content"
    strings:
        $s1 = "MSComctlLib.TreeCtrl.2"
        $s2 = "4D53436F6D63746C4C69622E547265654374726C2E32" nocase
        $s3 = "B69041C78985D111B16A00AA003F40D0" nocase
    $s4 = {B69041C78985D111B16A00AA003F40D0}
    $s5 = "C74190B6-8589-11D1-B16A-00AA003F40D0" nocase
    $s6 = "C74190B6-8589-11D1-B16A-00C0F0283628" nocase
    $s7 = {B69041C78985D111B16A00C0F0283628}
    $s8 = "B69041C78985D111B16A00C0F0283628" nocase
    $s9 = "objclass MSComctlLib.ImageComboCtl.2"
    $s10 = "MSComctlLib.ImageComboCtl.2"
    $s11 = {00 4D 53 43 6F 6D 63 74 6C 4C 69 62 2E 49 6D 61 67
        65 43 6F 6D 62 6F 43 74 6C}
    $s12 = {49006D0061006700650043006F006D0062006F00430074006C002000}
    $s13 = "TreeView1, 0, 0, MSComctlLib, TreeView"
    $s14 = "new ActiveXObject"
    $s15 = "<ax:ocx ax:classid=" ascii nocase

    
    condition:
        1 of them
    }