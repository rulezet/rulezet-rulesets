rule b02ecc516834373f753b4a56428780f1 {
	meta:
		description = "Auto-generated rule - file b02ecc516834373f753b4a56428780f1"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2016-11-14"
		hash1 = "c3b3fcc4d911d24473bf0a1b42e93de250b4ecf1b74632158a54c68013403613"
	strings:
		$s1 = "ProcessHostFactoryHelper" fullword ascii 
		$s2 = "Astray.exe" fullword wide 
		$s3 = "System.Web.Profile" fullword ascii 
		$s4 = "X509KeyUsageExtension" fullword ascii 
		$s5 = "DrawListViewColumnHeaderEventArgs" fullword ascii 
		$s6 = "Ascriptions Cheapest Inc Colleague Economised" fullword wide 
		$s7 = "-Ascriptions Cheapest Inc Colleague Economised" fullword ascii 
		$s8 = "jPuZOXwFDv.Properties.Resources.resources" fullword ascii 
		$s9 = "System.IO.Ports" fullword ascii 
		$s10 = "ShowSaveAsDialog" fullword ascii 
		$s11 = "HostingEnvironment" fullword ascii 
		$s12 = "DataGridViewComboBoxEditingControl" fullword ascii 
		$s13 = "get_jOMloqc" fullword ascii 
		$s14 = "jPuZOXwFDv.Properties.Resources" fullword wide 
		$s15 = "8.7.9.5" fullword wide 
		$s16 = "IPAddressCollection" fullword ascii 
		$s17 = "tgmFGETJ" fullword ascii 
		$s18 = "6.1.4.2" fullword wide 
		$s19 = "Competitive Containable" fullword wide 
		$s20 = "jPuZOXwFDv.Properties" fullword ascii 
	condition:
		( uint16(0) == 0x5a4d and filesize < 800KB and ( 10 of ($s*) ) ) or ( all of them )
}